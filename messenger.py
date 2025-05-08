from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import pickle


def serialize_key(key):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.private_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
    return key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
        
def deserialize_key(serialized_key):
    if isinstance(serialized_key, ec.EllipticCurvePrivateKey):
        return serialization.load_pem_private_key(serialized_key)
    return serialization.load_pem_public_key(serialized_key)

def calculate_ad(pub_key, n, pn):
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    pn_bytes = pn.to_bytes((pn.bit_length() + 7) // 8, byteorder='big')
    return pub_key + n_bytes + pn_bytes


def gov_decrypt(gov_priv, message):
    """ TODO: Dekripcija poruke unutar kriptosustava javnog kljuca `Elgamal`
        gdje, umjesto kriptiranja jasnog teksta množenjem u Z_p, jasni tekst
        kriptiramo koristeci simetricnu sifru AES-GCM.

        Procitati poglavlje `The Elgamal Encryption Scheme` u udzbeniku
        `Understanding Cryptography` (Christof Paar , Jan Pelzl) te obratiti
        pozornost na `Elgamal Encryption Protocol`

        Dakle, funkcija treba:
        1. Izracunati `masking key` `k_M` koristeci privatni kljuc `gov_priv` i
           javni kljuc `gov_pub` koji se nalazi u zaglavlju `header`.
        2. Iz `k_M` derivirati kljuc `k` za AES-GCM koristeci odgovarajucu
           funkciju za derivaciju kljuca.
        3. Koristeci `k` i AES-GCM dekriptirati `gov_ct` iz zaglavlja da se
           dobije `sending (message) key` `mk`
        4. Koristeci `mk` i AES-GCM dekriptirati sifrat `ciphertext` orginalne
           poruke.
        5. Vratiti tako dobiveni jasni tekst.

        Naravno, lokalne varijable mozete proizvoljno imenovati.  Zaglavlje
        poruke `header` treba sadrzavati polja `gov_pub`, `gov_iv` i `gov_ct`.
        (mozete koristiti postojeci predlozak).

    """
    header, ciphertext = message
    
    gov_iv = header.gov_iv
    gov_ct = header.gov_ct
    gov_pub = deserialize_key(header.gov_pub)
    
    gov_shared_secret = gov_priv.exchange(ec.ECDH(), gov_pub)
    
    salt = salt = b'\x00' * SHA256.digest_size
    gov_hkdf = HKDF (
        algorithm=SHA256(),
        length=80,
        salt=salt,
        info=b'gov_key_derive'
    )
    gov_derivate = gov_hkdf.derive(gov_shared_secret)
    
    decryption_key = gov_derivate[:32]
    
    aesgcm_key = AESGCM(decryption_key)
    encryption_key = aesgcm_key.decrypt(gov_iv, gov_ct, None)
    
    ad = calculate_ad(header.rat_pub, header.n, header.pn)
    
    aesgcm = AESGCM(encryption_key)
    plaintext = aesgcm.decrypt(header.iv, ciphertext, ad)
    
    return plaintext.decode()
    

# Možete se (ako želite) poslužiti sa sljedeće dvije strukture podataka
@dataclass
class Connection:
    dhs        : ec.EllipticCurvePrivateKey     # moj privatni DH kljuc
    dhr        : ec.EllipticCurvePublicKey      # tudji javni DH kljuc
    rk         : bytes = None                   # shared secret iz DH
    cks        : bytes = None                   # sending key
    ckr        : bytes = None                   # receiving key
    pn         : int = 0
    ns         : int = 0
    nr         : int = 0
    mk_skipped : dict = field(default_factory=dict)

@dataclass
class Header:
    rat_pub : bytes         # moj javni kljuc (koristi se za desifriranje)
    iv      : bytes
    gov_pub : bytes         # javni kljuc vlade
    gov_iv  : bytes
    gov_ct  : bytes         # sifriran sending key
    n       : int = 0
    pn      : int = 0

# Dopusteno je mijenjati sve osim sučelja.
class Messenger:
    """ Klasa koja implementira klijenta za čavrljanje
    """

    MAX_MSG_SKIP = 10

    def __init__(self, username, ca_pub_key, gov_pub):
        """ Inicijalizacija klijenta

        Argumenti:
            username (str)      --- ime klijenta
            ca_pub_key (class)  --- javni ključ od CA (certificate authority)
            gov_pub (class) --- javni ključ od vlade

        Returns: None
        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        self.gov_pub = gov_pub
        self.private_key = None
        self.conns = {}        

    def generate_certificate(self):
        """ TODO: Metoda generira i vraća certifikacijski objekt.

        Metoda generira inicijalni par Diffie-Hellman ključeva. Serijalizirani
        javni ključ, zajedno s imenom klijenta, pohranjuje se u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt može biti proizvoljnog
        tipa (npr. dict ili tuple). Za serijalizaciju ključa možete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        Returns: <certificate object>
        """        
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = self.private_key.public_key()

        serialized_public_key = serialize_key(public_key)
        public_key = serialized_public_key
        
        certificate_object = {
            'username': self.username,
            'serialized_public_key': serialized_public_key
        }
        
        return certificate_object
        
    def receive_certificate(self, cert_data, cert_sig):
        """ TODO: Metoda verificira certifikat od `CA` i sprema informacije o
                  klijentu.

        Argumenti:
        cert_data --- certifikacijski objekt
        cert_sig  --- digitalni potpis od `cert_data`

        Returns: None

        Metoda prima certifikat --- certifikacijski objekt koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta s kojim želi komunicirati te njegov
        potpis. Certifikat se verificira pomoću javnog ključa CA (Certificate
        Authority), a ako verifikacija uspije, informacije o klijentu (ime i javni
        ključ) se pohranjuju. Javni ključ CA je spremljen tijekom inicijalizacije
        objekta.

        U slučaju da verifikacija ne prođe uspješno, potrebno je baciti iznimku.

        """
        self.ca_pub_key.verify(cert_sig, pickle.dumps(cert_data), ec.ECDSA(SHA256()))
        
        username = cert_data['username']
        serialized_public_key = cert_data['serialized_public_key']

        connection = Connection(dhs=self.private_key, dhr=serialized_public_key)
        self.conns[username] = connection
    
    def KDF_RK(self, rk, dh_shared_secret):
        hkdf = HKDF(
            algorithm=SHA256(),
            length=96,
            salt=rk,
            info=b'kdf_rk'
        )
        derivate = hkdf.derive(dh_shared_secret)
        new_rk = derivate[:48]
        new_ck = derivate[48:]
        return new_rk, new_ck
    
    def KDF_CK(self, ck):
        # Derive message key using 0x01 as input
        hmac_ctx = hmac.HMAC(ck, SHA256())
        hmac_ctx.update(b'\x01')
        message_key = hmac_ctx.finalize()

        # Derive the next chain key using 0x02 as input
        hmac_ctx = hmac.HMAC(ck, SHA256())
        hmac_ctx.update(b'\x02')
        next_chain_key = hmac_ctx.finalize()
        
        return message_key, next_chain_key

    def send_message(self, username, message):
        """ TODO: Metoda šalje kriptiranu poruku `message` i odgovarajuće
                  zaglavlje korisniku `username`.

        Argumenti:
        message  --- poruka koju ćemo poslati
        username --- korisnik kojem šaljemo poruku

        returns: (header, ciphertext).

        Zaglavlje poruke treba sadržavati podatke potrebne
        1) klijentu da derivira nove ključeve i dekriptira poruku;
        2) Velikom Bratu da dekriptira `sending` ključ i dode do sadržaja poruke.

        Pretpostavite da već posjedujete certifikacijski objekt klijenta (dobiven
        pomoću metode `receive_certificate`) i da klijent posjeduje vaš. Ako
        prethodno niste komunicirali, uspostavite sesiju generiranjem ključeva po-
        trebnih za `Double Ratchet` prema specifikaciji. Inicijalni korijenski ključ
        (`root key` za `Diffie-Hellman ratchet`) izračunajte pomoću ključa
        dobivenog u certifikatu i vašeg inicijalnog privatnog ključa.

        Svaka poruka se sastoji od sadržaja i zaglavlja. Svaki put kada šaljete
        poruku napravite korak u lancu `symmetric-key ratchet` i lancu
        `Diffie-Hellman ratchet` ako je potrebno prema specifikaciji (ovo drugo
        možete napraviti i prilikom primanja poruke); `Diffie-Helman ratchet`
        javni ključ oglasite putem zaglavlja. S novim ključem za poruke
        (`message key`) kriptirajte i autentificirajte sadržaj poruke koristeći
        simetrični kriptosustav AES-GCM; inicijalizacijski vektor proslijedite
        putem zaglavlja. Dodatno, autentificirajte odgovarajuća polja iz
        zaglavlja, prema specifikaciji.

        Sve poruke se trebaju moći dekriptirati uz pomoć privatnog kljuca od
        Velikog brata; pripadni javni ključ dobiti ćete prilikom inicijalizacije
        kli- jenta. U tu svrhu koristite protokol enkripcije `ElGamal` tako da,
        umjesto množenja, `sending key` (tj. `message key`) kriptirate pomoću
        AES-GCM uz pomoć javnog ključa od Velikog Brata. Prema tome, neka
        zaglavlje do- datno sadržava polja `gov_pub` (`ephemeral key`) i
        `gov_ct` (`ciphertext`) koja predstavljaju izlaz `(k_E , y)`
        kriptosustava javnog kljuca `Elgamal` te `gov_iv` kao pripadni
        inicijalizacijski vektor.

        U ovu svrhu proučite `Elgamal Encryption Protocol` u udžbeniku
        `Understanding Cryptography` (glavna literatura). Takoder, pročitajte
        dokumentaciju funkcije `gov_decrypt`.

        Za zaglavlje možete koristiti već dostupnu strukturu `Header` koja sadrži
        sva potrebna polja.

        Metoda treba vratiti zaglavlje i kriptirani sadrzaj poruke kao `tuple`:
        (header, ciphertext).

        """
        if self.conns.get(username) is None:
            raise ValueError('Username not found.')
        
        conn = self.conns[username]
        user_public_key = deserialize_key(conn.dhr)
        
        # ako šaljemo više poruka bez mijenjanja root keya onda cks nije None
        if conn.cks is None:
            if conn.rk is None:
                my_private_key = conn.dhs

                shared_secret = my_private_key.exchange(ec.ECDH(), user_public_key)
                conn.rk = shared_secret
            
            new_private_key = ec.generate_private_key(ec.SECP384R1())
            conn.dhs = new_private_key
            new_dh_secret = new_private_key.exchange(ec.ECDH(), user_public_key)
            
            rk, ck = self.KDF_RK(conn.rk, new_dh_secret)
            conn.rk = rk
        else:
            ck = conn.cks   
            
        message_key, new_ck = self.KDF_CK(ck)
        conn.cks = new_ck
        conn.ckr = None
        
        salt = salt = b'\x00' * SHA256.digest_size
        hkdf = HKDF(
            algorithm=SHA256(),
            length=80,  # Generate 80 bytes of output
            salt=salt,
            info=b'message_key_derive'
        )
        derivate = hkdf.derive(message_key)
        
        encryption_key = derivate[:32]
        # authentication_key = derivate[32:64]
        iv = derivate[64:80]
        
        conn.ns += 1
        conn.pn += 1
        self.conns[username] = conn
        
        ad = calculate_ad(serialize_key(conn.dhs.public_key()), conn.ns, conn.pn)
        
        aesgcm_message = AESGCM(encryption_key)
        ciphertext = aesgcm_message.encrypt(iv, bytes(message, 'UTF-8'), ad)
        
        # vlada:
        gov_private_key = ec.generate_private_key(ec.SECP384R1())
        gov_shared_secret = gov_private_key.exchange(ec.ECDH(), self.gov_pub)
        gov_hkdf = HKDF (
            algorithm=SHA256(),
            length=80,
            salt=salt,
            info=b'gov_key_derive'
        )
        gov_derivate = gov_hkdf.derive(gov_shared_secret)
        
        gov_key = gov_derivate[:32]
        gov_iv = gov_derivate[64:80]
        
        gov_aesgcm = AESGCM(gov_key)
        gov_ct = gov_aesgcm.encrypt(gov_iv, encryption_key, None)
        
        
        header = Header(
            rat_pub=serialize_key(conn.dhs.public_key()),
            iv=iv,
            gov_pub=serialize_key(gov_private_key.public_key()),
            gov_iv=gov_iv,
            gov_ct=gov_ct,
            n=conn.ns,
            pn=conn.pn
        )
        
        return (header, ciphertext)
        

    def receive_message(self, username, message):
        """ TODO: Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- korisnik koji je poslao poruku

        returns: plaintext

        Metoda prima kriptiranu poruku od korisnika s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od korisnika
        (dobiven pomoću `receive_certificate`) i da je korisnik izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """
        if self.conns.get(username) is None:
            raise ValueError('Username not found.')
        
        header, ciphertext = message
        conn = self.conns[username]
        
        # provjeri je li dobivena poruka jedna od preskočenih
        if header.n in conn.mk_skipped:
            ck = conn.mk_skipped[header.n]
            
            message_key, _ = self.KDF_CK(ck)
            
            salt = b'\x00' * SHA256.digest_size
            hkdf = HKDF(
                algorithm=SHA256(),
                length=80,  # Generate 80 bytes of output
                salt=salt,
                info=b'message_key_derive'
            )
            derivate = hkdf.derive(message_key)
            decryption_key = derivate[:32]        
            ad = calculate_ad(header.rat_pub, header.n, header.pn)
            
            aesgcm_message = AESGCM(decryption_key)
            plaintext = aesgcm_message.decrypt(header.iv, ciphertext, ad)
            
            return plaintext.decode()
        
        # dobili smo poruku koja nije po redu
        while conn.nr + 1 < header.n:
            if conn.ckr is None:
                my_private_key = conn.dhs
                if conn.rk is None:
                    user_public_key = deserialize_key(conn.dhr)
                    
                    shared_secret = my_private_key.exchange(ec.ECDH(), user_public_key)
                    conn.rk = shared_secret
                
                new_user_public_key = deserialize_key(header.rat_pub)
                conn.dhr = header.rat_pub
                new_dh_secret = my_private_key.exchange(ec.ECDH(), new_user_public_key)
                
                rk, ck = self.KDF_RK(conn.rk, new_dh_secret)
                conn.rk = rk
            else:
                ck = conn.ckr
                
            _, new_ck = self.KDF_CK(ck)
            conn.ckr = new_ck
            conn.nr += 1
            
            conn.mk_skipped[conn.nr] = ck           
        
        if conn.ckr is None:
            my_private_key = conn.dhs
            if conn.rk is None:
                user_public_key = deserialize_key(conn.dhr)
                
                shared_secret = my_private_key.exchange(ec.ECDH(), user_public_key)
                conn.rk = shared_secret
            
            new_user_public_key = deserialize_key(header.rat_pub)
            conn.dhr = header.rat_pub
            new_dh_secret = my_private_key.exchange(ec.ECDH(), new_user_public_key)
            
            rk, ck = self.KDF_RK(conn.rk, new_dh_secret)
            conn.rk = rk
        else:
            ck = conn.ckr
            
        message_key, new_ck = self.KDF_CK(ck)
        conn.ckr = new_ck
        conn.cks = None
        
        conn.nr += 1
        conn.pn = 0     # resetiraj duljinu sending chaina
        
        self.conns[username] = conn
    
        salt = b'\x00' * SHA256.digest_size
        hkdf = HKDF(
            algorithm=SHA256(),
            length=80,  # Generate 80 bytes of output
            salt=salt,
            info=b'message_key_derive'
        )
        derivate = hkdf.derive(message_key)
        decryption_key = derivate[:32]        
        ad = calculate_ad(header.rat_pub, header.n, header.pn)
        
        aesgcm_message = AESGCM(decryption_key)
        plaintext = aesgcm_message.decrypt(header.iv, ciphertext, ad)
        
        return plaintext.decode()
        

def main():
    pass

if __name__ == "__main__":
    main()

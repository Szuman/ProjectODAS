# ProjectODAS
## Opis projektu:

Celem projektu jest opracowanie bezpiecznej aplikacji internetowej pozwalającej zalogowanemu użytkownikowi przechowywać jego hasła.
Użytkownik jest identyfikowany przy pomocy swojego loginu i hasła. Ponadto zna on hasło główne (master password) pozwalające odszyfrować hasła przechowywane w menedżerze.

## Aplikacja pozwala:

* na rejestrację nowego użytkownika,
* na zalogowanie/wylogowanie użytkownika,
* zapisać nowe hasło do wybranego serwisu (hasło, nazwę serwisu -- adres URL lub zwykły tekst),
* obejrzeć listę haseł (na liście wyświetla się nazwa serwisu),
* możemy odszyfrować wybrane hasło i je wyświetlić/skopiować do schowka.
* Należy skupić się na bezpieczeństwie aplikacji oraz bezpiecznej konfiguracji środowiska, w którym działa.

## Moduł uwierzytelniania powinien zakładać:

* walidację danych wejściowych (z negatywnym nastawieniem),
* opóźnienia i limity prób (żeby utrudnić zdalne zgadywanie i atak brute-force),
* ograniczone informowanie o błędach (np. o tym przyczynie odmowy uwierzytelenia),
* bezpieczne przechowywanie hasła (wykorzystanie kryptograficznych funcji mieszających, wykorzystanie soli, wielokrotne hashowanie)
* kontrola siły hasła, żeby uświadomić użytkownikowi problem
* monitorowanie pracy systemu (np. żeby poinformować użytkownika o nowych komputerach, które łączyły się z jego kontem)
* zarządzanie uprawnieniami do zasobów.

## Wymagania:

* aplikacja powinna posiadać relacyjną bazę danych (może być SQLite),
* połączenie z aplikacją powinno być szyfrowane (protokół HTTPS, z certyfikatem TLS/SSL -- może być samopodpisany),
* dane od użytkownika są walidowane z negatywnym nastawieniem,
* weryfikacja nieudanych prób logowania,
* aplikacja powinna sprawdzać jakość haseł i wymuszać silne hasła,
* dodanie opóźnienia podczas logowania

## Prezentacja strony znajduje się w pliku ODASprojektPrez.pdf

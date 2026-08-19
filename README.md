# Aprendizajes

Este documento recoge las ideas principales que vamos descubriendo al resolver
los retos de Cryptopals.

## Reto 4: detectar texto cifrado con XOR de un byte

El fichero de entrada contiene una línea cifrada con XOR de un byte entre muchas
líneas hexadecimales que no lo están. `challenge4.c` abre el fichero indicado
en la línea de comandos, lee una línea cada vez y elimina el salto de línea.
Cada línea representa bytes en hexadecimal: dos caracteres por cada byte.

En un cifrado XOR de un byte, una única clave `k` se repite para todos los
bytes:

```text
C[i] = P[i] XOR k
```

XOR es su propia inversa, por lo que se descifra con la misma operación:

```text
P[i] = C[i] XOR k
```

`fixed_xor_try()` aprovecha que la clave solo puede tener 256 valores. Para
cada valor entre `0x00` y `0xFF`, `generate_key()` crea su repetición con la
misma longitud que la línea y `fixed_xor()` aplica XOR byte a byte. Así obtiene
256 textos candidatos para cada línea, sin necesidad de conocer la clave.

Después, `score_hex_ascii_text()` valora cada candidato. La función suma más
puntos para espacios y letras frecuentes en inglés, como `t`, `e`, `a`, `i` u
`o`; los caracteres que no son letras ni espacios no aportan puntos. Se guarda
la clave y el texto de mayor puntuación de esa línea. `challenge4.c` compara
ese mejor resultado con el de las líneas anteriores y conserva el máximo
global en `candidate_line`.

Finalmente, `print_hex_as_ascii()` convierte de hexadecimal a texto el
candidato ganador. La puntuación es una heurística, no una prueba
criptográfica: puede fallar con textos cortos, idiomas distintos o contenido
que incluya muchos dígitos y signos de puntuación. Para este reto funciona
porque el texto oculto es inglés normal y destaca frente a resultados
aleatorios.

## Reto 5: XOR de clave repetida

El reto 5 implementa el cifrado XOR de clave repetida en
`src/repeating_xor.c`. A diferencia del reto 4, la clave no se limita a un
solo byte: sus bytes se reutilizan cíclicamente hasta cubrir todo el mensaje.
Para un texto `P` y una clave de longitud `m`, el cifrado es:

```text
C[i] = P[i] XOR K[i mod m]
```

Como XOR es reversible, descifrar usa exactamente la misma operación y la
misma clave. Con la clave `ICE`, por ejemplo, el cuarto byte vuelve a usar
`I`, el quinto `C` y el sexto `E`.

La función `repeating_xor()` trabaja con cadenas de texto que codifican bytes
en hexadecimal. Por eso comprueba que la entrada tenga un número par de
caracteres y avanza de dos en dos: `input_aux` y `key_aux` convierten cada par
hexadecimal a un byte, se aplica XOR, y el resultado se vuelve a escribir como
dos dígitos hexadecimales. Los índices de la clave se calculan con módulo para
volver al principio cuando se agota.

Las pruebas de `tests/challenge5_tests.cpp` convierten el texto ASCII y la
clave a hexadecimal con `ascii2hex_ascii()`. Verifican casos de error, un byte
idéntico que produce `00`, un fragmento corto y el texto completo con la clave
`ICE`.

Este esquema también se conoce como XOR de clave repetida o un Vigenère sobre
bytes. No es seguro: cada posición separada por la longitud de la clave se
cifra con el mismo byte de clave, lo que deja patrones estadísticos. Si se
estima la longitud de la clave, el criptograma puede dividirse en columnas y
atacar cada una como un XOR de un byte, que es la idea del reto 6.

## Reto 6: romper XOR de clave repetida

`challenge6.c` recibe un criptograma codificado en Base64. Primero concatena
sus líneas, lo decodifica con `base642bin()` y trabaja desde entonces con bytes
binarios. El objetivo es recuperar tanto la longitud de la clave repetida como
sus bytes.

El primer paso, `best_keysize()`, prueba longitudes de clave entre 2 y 39. Para
cada longitud divide el criptograma en bloques de ese tamaño y mide cuántos
bits son distintos entre bloques consecutivos. Esa es la distancia de Hamming,
que `hamming_distance()` calcula recorriendo los ocho bits de cada byte.

La distancia de Hamming es simplemente el número de posiciones de bits que
difieren entre dos datos de la misma longitud. Por ejemplo:

```text
A       = 01001001
B       = 01001111
A XOR B = 00000110
```

El resultado de XOR tiene dos bits a `1`, así que la distancia entre `A` y `B`
es 2. XOR deja un bit a `1` exactamente cuando los dos bits de entrada son
distintos; por eso contar sus bits a `1` produce la distancia.

La distancia se normaliza dividiéndola por la longitud del bloque y se promedia
para poder comparar claves de tamaños distintos. Funciona como estimador porque
la longitud correcta alinea los bloques con el período de la clave. Si la clave
mide `k` bytes, para dos posiciones separadas por `k` se cumple:

```text
C[i]     = P[i]     XOR K[i mod k]
C[i + k] = P[i + k] XOR K[i mod k]

C[i] XOR C[i + k] = P[i] XOR P[i + k]
```

Los dos bytes de clave se cancelan al aplicar XOR. Por eso, la distancia de
Hamming entre bloques cifrados de tamaño `k` coincide con la distancia entre
los fragmentos correspondientes de texto plano. El texto natural no es
aleatorio —contiene letras, espacios y patrones—, de modo que sus fragmentos
suelen diferir en menos bits que secuencias de bytes aleatorios.

Con una longitud candidata incorrecta, los bloques no se alinean con la clave:

```text
C[i] XOR C[i + n] = P[i] XOR P[i + n] XOR K[a] XOR K[b]
```

Normalmente `a` y `b` son distintos. La diferencia adicional entre ambos bytes
de clave introduce ruido y eleva la distancia media. Por ello, una longitud
con distancia normalizada baja es una buena candidata.

No es una garantía: con poco texto las medias pueden ser engañosas y un
múltiplo de la longitud real también puede alinear la clave y puntuar bien.
Conviene conservar varios tamaños candidatos y probar el descifrado completo
con todos ellos, en lugar de fiarse de un único mínimo.

Una vez estimado `best_keysiz`, el programa transpone el criptograma. La
columna `c` contiene los bytes de índices `c`, `c + best_keysiz`,
`c + 2 * best_keysiz`, etc. Todos ellos fueron cifrados con el mismo byte de
clave, por lo que cada columna equivale a un problema del reto 4.

`fixed_xor_bin_try()` prueba los 256 valores para ese byte, aplica XOR a la
columna y usa `score_bytes()` para elegir el resultado que más se parece a
texto inglés. El byte ganador se guarda en `key[c]`. Finalmente, el bucle
`plain[i] = bin[i] ^ key[i % best_keysiz]` aplica la clave reconstruida al
criptograma completo y recupera el texto.

Además, hay un límite que corregir en la versión actual de `best_keysize()`:
cuenta `blocks` bloques completos, pero compara cada uno con el siguiente,
incluido el último. Ese último acceso puede leer más allá de `bin`; debe
comparar solo `blocks - 1` pares y dividir la media entre el número de pares
realmente comparados.

## Reto 8: detectar AES en modo ECB

El reto recibe un fichero con varios criptogramas, uno por línea y codificados
en hexadecimal. `challenge8.c` convierte cada línea a bytes con `str2bytes()`
y la divide conceptualmente en bloques de 16 bytes, que es el tamaño de bloque
de AES.

ECB cifra cada bloque de manera independiente y determinista con la misma
clave:

```text
Cᵢ = AESₖ(Pᵢ)
```

Por ello, dos bloques de texto plano idénticos producen dos bloques cifrados
idénticos:

```text
Pᵢ = Pⱼ  =>  AESₖ(Pᵢ) = AESₖ(Pⱼ)  =>  Cᵢ = Cⱼ
```

Esta propiedad filtra patrones del mensaje. Por ejemplo, una imagen con zonas
uniformes o un texto con muchas repeticiones seguirá mostrando bloques iguales
después de cifrarse en ECB. En modos encadenados, como CBC con un IV adecuado,
los bloques iguales no tienen por qué producir el mismo resultado.

`aes128_check_repeated_blocks()` compara todos los pares distintos de bloques
de una línea mediante `memcmp()`. Incrementa la puntuación por cada pareja
idéntica; si un valor aparece tres veces, aporta tres parejas coincidentes. El
programa muestra las líneas cuya puntuación es mayor que cero, que son las
candidatas a haber sido cifradas en ECB.

La repetición no demuestra por sí sola que se haya usado ECB: puede existir una
colisión accidental, aunque entre bloques AES de 128 bits es extremadamente
improbable, o el dato puede contener bloques repetidos sin ser un criptograma
ECB. En este reto los datos están construidos para que la línea ECB contenga
repeticiones claras. La lección práctica es no usar ECB para datos
estructurados; un modo autenticado como AES-GCM evita tanto esta filtración de
patrones como la falta de integridad.

## Reto 9: padding PKCS#7

Los cifrados por bloques, como AES, procesan cantidades exactas de un bloque:
AES usa bloques de 16 bytes. Si el mensaje no ocupa un número múltiplo del
tamaño de bloque, no puede cifrarse directamente en modos como ECB o CBC. El
*padding* rellena el final del mensaje para alcanzar ese múltiplo.

PKCS#7 usa como relleno el número de bytes que se añaden, repetido una vez por
cada byte de padding. Para un mensaje de longitud `n` y bloques de tamaño `B`:

```text
p = B - (n mod B)
```

Se añaden `p` bytes, todos con el valor `p`. Por ejemplo, para el texto de 16
bytes `YELLOW SUBMARINE` y un bloque de 20 bytes, se añaden cuatro bytes:

```text
YELLOW SUBMARINE 04 04 04 04
```

Si faltan tres bytes para completar un bloque de cuatro, se añaden
`03 03 03`. Un caso importante es el de un mensaje que ya ocupa un bloque
completo: PKCS#7 añade un bloque entero. Con 16 bytes y bloques de 16, el
resultado termina en dieciséis bytes `10`. Esto permite diferenciar un último
byte de datos con valor `01`, por ejemplo, de un byte de padding.

`pkcs7_needed_pad()` calcula `p` y `pkcs7_pad()` escribe esos bytes al final
del buffer. La función requiere que el llamador proporcione capacidad suficiente
para el mensaje y el padding; devuelve el número de bytes añadidos o `-1` ante
un error.

Al descifrar, `pkcs7_unpad()` toma el último byte como longitud candidata del
relleno. Lo acepta solo si es distinto de cero, no supera el tamaño de bloque
ni la longitud disponible, y todos los últimos `p` bytes tienen exactamente el
mismo valor. Si es válido, devuelve la longitud sin padding; si no, devuelve
`-1`. Así rechaza, por ejemplo, los finales `05 05 05 05` cuando el último byte
indica cinco bytes, o `01 02 03 04`, cuyos valores no coinciden.

El padding solo ajusta la longitud; no autentica el mensaje ni protege su
integridad. Además, exponer de forma distinguible un error de padding puede
crear un oráculo de padding, como el que se explota en el reto 17.

## Reto 10: implementar CBC a partir de ECB

El reto 10 descifra un archivo Base64 cifrado con AES-128-CBC. El programa
concatena y decodifica las líneas de entrada, usa la clave conocida `YELLOW
SUBMARINE` y un IV de ceros —valores fijados por el ejercicio— y recupera el
texto bloque a bloque.

ECB cifra cada bloque de forma independiente:

```text
Cᵢ = Eₖ(Pᵢ)
```

Por eso filtra patrones: dos bloques iguales de texto plano generan el mismo
bloque cifrado. CBC (*Cipher Block Chaining*) evita esa independencia mezclando
cada bloque con el bloque cifrado anterior antes de cifrarlo:

```text
C₀ = Eₖ(P₀ XOR IV)
Cᵢ = Eₖ(Pᵢ XOR Cᵢ₋₁)    para i > 0
```

Aunque `Pᵢ` y `Pⱼ` sean iguales, normalmente sus bloques anteriores son
distintos, por lo que sus entradas a AES y sus bloques cifrados también lo son.
El IV cumple ese papel para el primer bloque. Debe ser impredecible y nuevo
para cada cifrado con una misma clave; no necesita ser secreto y se transmite
junto al criptograma. Un IV fijo de ceros, como el usado por el reto, es útil
para reproducir el ejemplo, pero no es seguro en una aplicación real.

Para descifrar CBC se aplica primero la inversa de AES al bloque actual y luego
XOR con el bloque cifrado anterior:

```text
P₀ = Dₖ(C₀) XOR IV
Pᵢ = Dₖ(Cᵢ) XOR Cᵢ₋₁    para i > 0
```

Esto es exactamente lo que hace la `aes128_cbc_decrypt()` local de
`challenge10.c`. Inicializa OpenSSL en ECB para obtener `Dₖ(Cᵢ)` de cada bloque
de 16 bytes y `buffer_xor()` mezcla después el IV en el primer bloque o el
bloque cifrado anterior en los siguientes. Así demuestra que CBC puede
construirse a partir de una primitiva ECB y XOR.

CBC oculta los patrones que ECB deja visibles, pero no aporta autenticación:
un atacante puede modificar bloques cifrados y provocar cambios previsibles
en el siguiente bloque de texto plano. Actualmente debe preferirse un modo
autenticado, como AES-GCM o ChaCha20-Poly1305, que proporciona confidencialidad
e integridad.

## Reto 12: descifrar un sufijo secreto byte a byte en ECB

`challenge12.c` construye un oráculo de cifrado. Al iniciarse genera una clave
AES aleatoria que se mantiene fija, y `encryption_oracle()` cifra lo siguiente
en ECB:

```text
entrada_controlada || sufijo_secreto || padding_PKCS#7
```

El sufijo está codificado en Base64 en `g_unknown_string`, pero Base64 solo es
una codificación: el oráculo lo decodifica antes de cifrarlo. El atacante no
conoce ni la clave ni el sufijo, pero puede enviar tantas entradas controladas
como quiera y observar el texto cifrado resultante.

Antes del ataque, `detect_blk_size()` llama al oráculo con entradas de `A` cada
vez más largas. Cuando la longitud cifrada aumenta, ha empezado un nuevo
bloque; la diferencia de longitudes revela el tamaño de bloque, 16 bytes para
AES. `detect_ecb()` envía varios bloques idénticos de `A` y busca bloques
cifrados repetidos. La repetición confirma que el oráculo usa ECB, condición
necesaria para el ataque.

Para recuperar el byte secreto de índice `n`, el programa calcula:

```text
bloque_objetivo = n / 16
prefijo = 15 - (n mod 16)
```

Al enviar solo `prefijo` bytes `A`, el byte secreto `S[n]` queda como último
byte del bloque objetivo. El programa guarda el bloque cifrado correspondiente
como referencia.

Después crea un diccionario de 256 posibilidades. Para cada byte candidato
`g`, envía:

```text
A...A || S[0] || S[1] || ... || S[n-1] || g
```

Los bytes `S[0..n-1]` ya se recuperaron en iteraciones anteriores. Si `g` es
igual a `S[n]`, el bloque de texto plano construido por el atacante es idéntico
al bloque objetivo de la consulta de referencia. Como ECB cifra bloques iguales
con la misma clave en el mismo resultado, los bloques cifrados coinciden. La
comparación con `memcmp()` identifica el candidato correcto y el proceso se
repite para el siguiente byte.

Un ejemplo con bloques imaginarios de cuatro bytes aclara la comparación.
Supongamos que el secreto empieza por `DOG...` y queremos obtener el primer
byte. Primero enviamos tres `A`:

```text
entrada del atacante:                 AAA
texto que cifra el oráculo:           AAADOG...
primer bloque de referencia:          AAAD
```

El atacante guarda ese bloque cifrado de referencia; aquí lo llamamos cifrado
de `AAAD` porque conocemos el ejemplo, pero el atacante aún no conoce `D` ni
la clave. Luego prueba `AAAX` para cada posible byte `X`; el primer bloque
cifrado solo coincidirá con el de referencia cuando `X` sea `D`, porque
entonces ambos bloques de texto plano son `AAAD`.

Para recuperar el segundo byte, el atacante ya conoce `D`. Envía dos `A`, con
lo que el bloque de referencia pasa a ser `AADO`, y compara su cifrado con los
de `AADA`, `AADB`, `AADC`, etc. La coincidencia se produce con `AADO`, por lo
que el segundo byte es `O`. El mismo desplazamiento y la misma búsqueda se
repiten para el resto del sufijo; al cruzar un límite de bloque se compara el
siguiente bloque cifrado.

Visto como una secuencia, para cada byte nuevo se quita una `A` del prefijo.
Así se mantiene el siguiente byte secreto justo al final del bloque de
referencia:

```text
Descubrir D:  AAA + DOG...  -> bloque AAAD
Descubrir O:  AA  + DOG...  -> bloque AADO   (D ya se conoce)
Descubrir G:  A   + DOG...  -> bloque ADOG   (D y O ya se conocen)
```

En las 256 pruebas de una misma ronda el prefijo no cambia. En esas pruebas se
añade al prefijo la parte del secreto ya descubierta y únicamente se varía el
último byte. Por ejemplo, al buscar `O` se mantiene `AA` y el `D` recuperado:
`AADA`, `AADB`, `AADC`, ..., `AADO`. La coincidencia de `AADO` revela `O`.
Entonces se pasa a la siguiente ronda, se elimina otra `A` y se incorpora `O`
a los bytes ya conocidos: para buscar `G` se probarán `ADOA`, `ADOB`, ...,
`ADOG`.

La debilidad no consiste en que la clave sea corta o predecible: incluso una
clave AES aleatoria es insuficiente si un atacante puede consultar un oráculo
ECB determinista que concatena un secreto. El ataque requiere que la clave se
mantenga fija, que el atacante controle el prefijo y que no haya un prefijo
aleatorio desconocido; el caso con ese prefijo se trata en el reto 14.

El bucle actual termina cuando ningún candidato produce coincidencia. Una
implementación más robusta calcularía primero la longitud exacta del sufijo y
trataría explícitamente el padding, para no confundir el final del secreto con
un byte de padding recuperable. En sistemas reales debe evitarse ECB y usarse
cifrado autenticado con nonces o IVs adecuados.

## Reto 13: ataque ECB cut-and-paste

El reto modela una aplicación que guarda en una cookie cifrada el perfil de
cada usuario. El servidor descifra la cookie y confía en el campo `role` para
decidir sus privilegios. Un usuario normal recibe `role=user`; el objetivo del
atacante es fabricar una cookie que el servidor interprete como `role=admin`,
sin conocer la clave AES ni poder pedir ese rol directamente.

Hay dos operaciones que, en una aplicación real, pertenecerían al servidor:

1. `profile_for(email)` recibe el correo enviado por el cliente y crea el
   texto de perfil.
2. `encrypt_profile(profile)` aplica padding y devuelve el perfil cifrado que
   el servidor entregaría al navegador como cookie.

`main()` llama ambas funciones directamente porque es una demostración local.
No significa que el atacante pueda invocar funciones internas del servidor:
el supuesto del reto es que puede usar repetidamente el endpoint normal de
registro o actualización de perfil, elegir el valor de su correo y recibir la
cookie cifrada resultante. No puede solicitar que el servidor asigne
`role=admin`; todos los perfiles que el servidor genera tienen inicialmente
`role=user`.

El texto que el servidor forma tiene este formato:

```text
email=<correo>&uid=10&role=user
```

El *filtrado de caracteres* es una validación de la entrada. `profile_for()`
busca `&` y `=` dentro del correo y rechaza la petición si encuentra alguno.
Esos caracteres tienen significado en este formato: `&` separa campos y `=`
asigna un valor. Sin ese filtro, un atacante podría enviar literalmente:

```text
alice@example.com&role=admin
```

y conseguir que el texto del perfil incorporase otro campo `role`. Con el
filtro, esa inyección directa falla; el atacante solo puede elegir correos sin
`&` ni `=`. Por ejemplo, el servidor acepta `AAAAAAAAAAAAA` y devuelve el
perfil cifrado correspondiente. Después `encrypt_profile()` aplica PKCS#7 y
cifra el perfil con AES-ECB bajo una clave aleatoria fija que el atacante no
conoce.

El filtrado de caracteres no basta porque ECB cifra cada bloque de 16 bytes de
forma independiente y determinista. Si se conoce el contenido y la alineación
de un bloque, su cifrado puede copiarse a otra posición sin descifrarlo:

```text
Eₖ(P) = C  =>  insertar C en otro criptograma produce P al descifrar
```

Primero el programa solicita el perfil del correo con trece `A`:

```text
email=AAAAAAAAAAAAA&uid=10&role=user
|------ bloque 0 ------|------ bloque 1 ------| bloque 2
```

`email=` ocupa 6 bytes; con 13 `A` y los 13 bytes de `&uid=10&role=` se llega
exactamente a 32 bytes. Por tanto, `user` y su padding ocupan el último bloque.
Ese es el bloque que se quiere reemplazar.

Después construye otro correo con diez `A`, seguido de `admin` y once bytes
`0x0b`. El prefijo `email=` más las diez `A` llenan el primer bloque; el segundo
queda exactamente así:

```text
admin 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b
```

Es un bloque PKCS#7 válido: `admin` tiene 5 bytes y los 11 bytes restantes
valen `0x0b`. El programa copia el segundo bloque cifrado de este perfil al
último bloque cifrado del primer perfil. Al descifrar el criptograma mezclado,
los dos primeros bloques siguen formando `email=...&uid=10&role=` y el último
se convierte en `admin` con padding válido. Tras eliminar el padding, el perfil
resultante indica `role=admin`.

El ataque no rompe AES: reutiliza bloques válidos producidos por el propio
servicio. Requiere una clave ECB fija, la capacidad de elegir parte del texto
plano y ausencia de autenticación. CBC sin autenticación también es maleable,
aunque el ataque concreto de copiar bloques no funciona igual por el
encadenamiento. La defensa moderna es un modo autenticado, como AES-GCM o
ChaCha20-Poly1305, que detecta cualquier modificación del criptograma.

## Reto 17: ataque de oráculo de padding en CBC

`challenge17.c` simula un servicio que cifra uno de diez mensajes codificados
en Base64. `encryption_oracle()` elige el mensaje, lo decodifica, aplica
padding PKCS#7 y lo cifra con AES-CBC usando una clave global aleatoria y un IV
aleatorio. El atacante recibe solo el IV y el texto cifrado.

La función `padding_oracle()` representa la vulnerabilidad: descifra los datos
y responde únicamente si el padding PKCS#7 es válido. En un servicio real esa
respuesta suele filtrarse mediante mensajes de error, códigos HTTP o tiempos
de respuesta distintos. Aunque no revela directamente el texto, basta para
recuperarlo.

Para un bloque cifrado `Cᵢ`, CBC calcula el texto plano como:

```text
Pᵢ = Dₖ(Cᵢ) XOR Cᵢ₋₁
```

Para el primer bloque, `Cᵢ₋₁` es el IV. `attack_block()` conserva `Cᵢ` y
modifica el bloque anterior —o el IV— que entrega al oráculo. Ataca de derecha
a izquierda para forzar primero un padding `0x01`, después `0x02 0x02`, y así
hasta completar los 16 bytes del bloque.

La variable `deciphered` guarda el valor intermedio `Dₖ(Cᵢ)`. Si una prueba
`modified_blk[b]` hace válido un padding de valor `pad`, se cumple:

```text
modified_blk[b] XOR Dₖ(Cᵢ)[b] = pad
```

Por tanto el código obtiene el byte intermedio como
`modified_blk[b] XOR pad` y recupera el texto plano aplicándole XOR con el
byte original del bloque anterior. Los bytes que ya se conocen se ajustan en
cada iteración para que continúen formando el nuevo padding deseado.

`attack()` repite este procedimiento para cada bloque, usando el IV como
bloque previo del primero y el bloque cifrado anterior para los demás. Al
final, `pkcs7_unpad()` elimina el padding recuperado. La enseñanza es que CBC
sin autenticación no es seguro cuando un atacante puede distinguir un error de
padding: hay que usar un modo autenticado, como AES-GCM o ChaCha20-Poly1305,
y no exponer errores de descifrado diferenciables.

## Reto 23: clonar un MT19937 a partir de sus salidas

MT19937 no es un generador criptográficamente seguro. Aunque su estado interno
tiene 624 palabras de 32 bits, cada llamada al generador expone una palabra de
ese estado después de aplicar una transformación reversible denominada
*tempering*.

La salida se calcula aplicando estas operaciones XOR y desplazamientos:

```c
y ^= y >> 11;
y ^= (y << 7) & 0x9D2C5680;
y ^= (y << 15) & 0xEFC60000;
y ^= y >> 18;
```

Para recuperar el estado original hay que deshacerlas en orden inverso. Un XOR
con un desplazamiento puede invertirse de forma iterativa: los bits que no
dependen de otros se conservan y permiten recuperar progresivamente los demás.
Por eso, al deshacer una operación se parte de la salida conocida y se repite
la misma relación hasta reconstruir los 32 bits.

Al observar 624 salidas consecutivas y aplicar `untemper` a cada una obtenemos
las 624 palabras del estado interno. Si el clon deja su índice en 624, ambos
generadores ejecutarán el mismo `twist` antes de producir la siguiente salida,
por lo que a partir de ese momento entregarán exactamente la misma secuencia.

La conclusión práctica es importante: MT19937 sirve para simulaciones o usos
no sensibles, pero nunca para generar secretos, tokens de sesión, nonces ni
claves. Si un atacante puede observar suficientes salidas, puede predecir todas
las futuras.

## Reto 24: semillas de 16 bits

Una semilla de 16 bits solo tiene 65.536 valores posibles. Aunque se genere
con una fuente criptográficamente segura, ese espacio es lo bastante pequeño
para probar exhaustivamente todas las semillas y recuperar la correcta si se
conoce parte del texto plano. La calidad de la fuente aleatoria no compensa un
tamaño de semilla insuficiente.

Un cifrador de flujo genera una secuencia de bytes (*keystream*) y aplica XOR
byte a byte con el texto plano. En este reto, cada salida de 32 bits de MT19937
se divide explícitamente, de menos a más significativo, en cuatro bytes de la
secuencia.

MT19937 es determinista: inicializarlo de nuevo con la misma semilla produce
el mismo *keystream*. Como XOR es su propia inversa, esa misma rutina sirve
para cifrar y descifrar siempre que reciba la misma semilla.

Un sufijo conocido de texto plano permite comprobar candidatas a semilla: se
descifra el final del mensaje con cada *keystream* candidato y se busca que
coincida con ese sufijo. En este reto usamos catorce caracteres `A` conocidos.
Recorrer las 65.536 semillas posibles es un ataque de fuerza bruta asequible.

Un timestamp no es una semilla secreta: un atacante puede aproximar el momento
de creación de un token y probar las semillas de ese intervalo. Por ello,
MT19937 inicializado con la hora actual tampoco sirve para crear tokens de
seguridad.

Si se conoce que el token se generó hace menos de 256 segundos, basta con
probar esos timestamps recientes y comparar los tokens generados. El espacio
de búsqueda queda reducido a unas pocas centenas de candidatas.

Para reproducir el ataque no es necesario esperar físicamente: se puede
simular un instante posterior al de creación y buscar hacia atrás desde él.

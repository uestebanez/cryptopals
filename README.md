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

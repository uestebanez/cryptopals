#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \return 0 if sucess, -1 if error
 */
int random_bytes(uint8_t* buffer, size_t len);

/**
 * \brief return a random value in the given range [min-max]
 * \return 0 if success, -1 if error
 * \remarks srand should be called before using the function
 */
int random_range(size_t min, size_t max, size_t* out);

#ifdef __cplusplus
}
#endif /* __cplusplus */



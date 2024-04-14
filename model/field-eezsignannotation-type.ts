/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The type of the Ezsignannotation.  1. **StrikethroughBlock** is a box with hatching. 2. **StrikethroughLine** is a red line to cross words. 3. **Text** is a simple Text.
 * @export
 * @enum {string}
 */

export const FieldEEzsignannotationType = {
    StrikethroughBlock: 'StrikethroughBlock',
    StrikethroughLine: 'StrikethroughLine',
    Text: 'Text'
} as const;

export type FieldEEzsignannotationType = typeof FieldEEzsignannotationType[keyof typeof FieldEEzsignannotationType];




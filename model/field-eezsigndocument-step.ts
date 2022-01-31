/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The signature step of the Ezsigndocument.
 * @export
 * @enum {string}
 */

export const FieldEEzsigndocumentStep = {
    Unsent: 'Unsent',
    Unsigned: 'Unsigned',
    PartiallySigned: 'PartiallySigned',
    DeclinedToSign: 'DeclinedToSign',
    PrematurelyEnded: 'PrematurelyEnded',
    Completed: 'Completed'
} as const;

export type FieldEEzsigndocumentStep = typeof FieldEEzsigndocumentStep[keyof typeof FieldEEzsigndocumentStep];




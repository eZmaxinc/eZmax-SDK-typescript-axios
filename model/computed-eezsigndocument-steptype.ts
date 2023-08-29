/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Indicates whether the current step is a form or signatures.
 * @export
 * @enum {string}
 */

export const ComputedEEzsigndocumentSteptype = {
    Form: 'Form',
    Sign: 'Sign',
    None: 'None'
} as const;

export type ComputedEEzsigndocumentSteptype = typeof ComputedEEzsigndocumentSteptype[keyof typeof ComputedEEzsigndocumentSteptype];




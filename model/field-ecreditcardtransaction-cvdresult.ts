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
 * The result for the cvd validation
 * @export
 * @enum {string}
 */

export const FieldECreditcardtransactionCvdresult = {
    Match: 'Match',
    NoMatch: 'NoMatch',
    NotVerified: 'NotVerified'
} as const;

export type FieldECreditcardtransactionCvdresult = typeof FieldECreditcardtransactionCvdresult[keyof typeof FieldECreditcardtransactionCvdresult];




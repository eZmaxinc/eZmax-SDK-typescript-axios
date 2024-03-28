/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Subscription level when a user has a Prepaid subscription.
 * @export
 * @enum {string}
 */

export const FieldEUserEzsignprepaid = {
    No: 'No',
    Basic: 'Basic',
    Standard: 'Standard',
    Pro: 'Pro'
} as const;

export type FieldEUserEzsignprepaid = typeof FieldEUserEzsignprepaid[keyof typeof FieldEUserEzsignprepaid];




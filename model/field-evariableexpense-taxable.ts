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
 * The taxable of the Variableexpense
 * @export
 * @enum {string}
 */

export const FieldEVariableexpenseTaxable = {
    Yes: 'Yes',
    No: 'No',
    Included: 'Included'
} as const;

export type FieldEVariableexpenseTaxable = typeof FieldEVariableexpenseTaxable[keyof typeof FieldEVariableexpenseTaxable];



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
 * The type of the Ezsigntemplatepackage.
 * @export
 * @enum {string}
 */

export const FieldEEzsigntemplatepackageType = {
    Company: 'Company',
    Department: 'Department',
    Team: 'Team',
    User: 'User',
    Usergroup: 'Usergroup'
} as const;

export type FieldEEzsigntemplatepackageType = typeof FieldEEzsigntemplatepackageType[keyof typeof FieldEEzsigntemplatepackageType];



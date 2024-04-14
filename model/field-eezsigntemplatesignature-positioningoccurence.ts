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
 * The occurence of the pattern to add the Ezsigntemplatesignature  This will be required if **eEzsigntemplatesignaturePositioning** is set to **PerCoordinates**
 * @export
 * @enum {string}
 */

export const FieldEEzsigntemplatesignaturePositioningoccurence = {
    All: 'All',
    First: 'First',
    Last: 'Last'
} as const;

export type FieldEEzsigntemplatesignaturePositioningoccurence = typeof FieldEEzsigntemplatesignaturePositioningoccurence[keyof typeof FieldEEzsigntemplatesignaturePositioningoccurence];



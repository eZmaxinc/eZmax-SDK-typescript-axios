/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Indicates if the Ezsigndocument is completed when all signatures of this Ezsigndocument were applied or when all signatures of all Ezsigndocument  were applied
 * @export
 * @enum {string}
 */

export const FieldEEzsignfoldertypeCompletion = {
    PerEzsigndocument: 'PerEzsigndocument',
    PerEzsignfolder: 'PerEzsignfolder'
} as const;

export type FieldEEzsignfoldertypeCompletion = typeof FieldEEzsignfoldertypeCompletion[keyof typeof FieldEEzsignfoldertypeCompletion];




/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The signature step of the Ezsignfolder.
 * @export
 * @enum {string}
 */

export const FieldEEzsignfolderStep = {
    Unsent: 'Unsent',
    Sent: 'Sent',
    PartiallySigned: 'PartiallySigned',
    Expired: 'Expired',
    Completed: 'Completed',
    Archived: 'Archived',
    Disposed: 'Disposed'
} as const;

export type FieldEEzsignfolderStep = typeof FieldEEzsignfolderStep[keyof typeof FieldEEzsignfolderStep];




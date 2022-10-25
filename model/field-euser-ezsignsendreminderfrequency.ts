/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Frequency at which reminders will be sent to signers that haven\'t signed the documents
 * @export
 * @enum {string}
 */

export const FieldEUserEzsignsendreminderfrequency = {
    None: 'None',
    Daily: 'Daily',
    Weekly: 'Weekly'
} as const;

export type FieldEUserEzsignsendreminderfrequency = typeof FieldEUserEzsignsendreminderfrequency[keyof typeof FieldEUserEzsignsendreminderfrequency];




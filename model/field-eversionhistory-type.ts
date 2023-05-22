/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The type of Versionhistory.
 * @export
 * @enum {string}
 */

export const FieldEVersionhistoryType = {
    AgentBroker: 'AgentBroker',
    NewFeature: 'NewFeature',
    Correction: 'Correction',
    Modification: 'Modification',
    ImportantMessage: 'ImportantMessage'
} as const;

export type FieldEVersionhistoryType = typeof FieldEVersionhistoryType[keyof typeof FieldEVersionhistoryType];




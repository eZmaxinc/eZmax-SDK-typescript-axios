/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * An Activesession->Apikey object and children to create a complete structure
 * @export
 * @interface ActivesessionResponseCompoundApikey
 */
export interface ActivesessionResponseCompoundApikey {
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof ActivesessionResponseCompoundApikey
     */
    'pkiApikeyID': number;
    /**
     * The description of the Apikey in the language of the requester
     * @type {string}
     * @memberof ActivesessionResponseCompoundApikey
     */
    'sApikeyDescriptionX': string;
}


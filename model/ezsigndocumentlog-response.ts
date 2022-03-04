/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.6
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { FieldEEzsigndocumentlogType } from './field-eezsigndocumentlog-type';

/**
 * An Ezsigndocumentlog Object
 * @export
 * @interface EzsigndocumentlogResponse
 */
export interface EzsigndocumentlogResponse {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsigndocumentlogResponse
     */
    'fkiUserID': number | null;
    /**
     * The unique ID of the Ezsignsigner
     * @type {number}
     * @memberof EzsigndocumentlogResponse
     */
    'fkiEzsignsignerID': number | null;
    /**
     * The date and time at which the event was logged
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    'dtEzsigndocumentlogDatetime': string;
    /**
     * 
     * @type {FieldEEzsigndocumentlogType}
     * @memberof EzsigndocumentlogResponse
     */
    'eEzsigndocumentlogType': FieldEEzsigndocumentlogType;
    /**
     * The detail of the Ezsigndocumentlog
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    'sEzsigndocumentlogDetail': string;
    /**
     * The last name of the User or Ezsignsigner
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    'sEzsigndocumentlogLastname': string;
    /**
     * The first name of the User or Ezsignsigner
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    'sEzsigndocumentlogFirstname': string;
    /**
     * Represent an IP address.
     * @type {string}
     * @memberof EzsigndocumentlogResponse
     */
    'sEzsigndocumentlogIP': string;
}


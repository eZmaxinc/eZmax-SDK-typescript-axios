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


import { FieldEUserTypeSSPR } from './field-euser-type-sspr';

/**
 * Request for the /1/module/sspr/sendUsernames API Request
 * @export
 * @interface SsprSendUsernamesV1Request
 */
export interface SsprSendUsernamesV1Request {
    /**
     * The customer code assigned to your account
     * @type {string}
     * @memberof SsprSendUsernamesV1Request
     */
    'pksCustomerCode': string;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof SsprSendUsernamesV1Request
     */
    'fkiLanguageID': number;
    /**
     * 
     * @type {FieldEUserTypeSSPR}
     * @memberof SsprSendUsernamesV1Request
     */
    'eUserTypeSSPR': FieldEUserTypeSSPR;
    /**
     * The email address.
     * @type {string}
     * @memberof SsprSendUsernamesV1Request
     */
    'sEmailAddress': string;
}


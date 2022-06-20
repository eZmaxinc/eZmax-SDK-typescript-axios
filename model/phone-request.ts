/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { FieldEPhoneType } from './field-ephone-type';

/**
 * A Phone Object
 * @export
 * @interface PhoneRequest
 */
export interface PhoneRequest {
    /**
     * The unique ID of the Phonetype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home| |3|Mobile| |4|Fax| |5|Pager| |6|Toll Free|
     * @type {number}
     * @memberof PhoneRequest
     */
    'fkiPhonetypeID': number;
    /**
     * 
     * @type {FieldEPhoneType}
     * @memberof PhoneRequest
     */
    'ePhoneType': FieldEPhoneType;
    /**
     * The region of the phone number. (For a North America Number only)  The region is the \"514\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequest
     */
    'sPhoneRegion'?: string;
    /**
     * The exchange of the phone number. (For a North America Number only)  The exchange is the \"990\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequest
     */
    'sPhoneExchange'?: string;
    /**
     * The number of the phone number. (For a North America Number only)  The number is the \"1516\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof PhoneRequest
     */
    'sPhoneNumber'?: string;
    /**
     * A phone number in E.164 Format
     * @type {string}
     * @memberof PhoneRequest
     */
    'sPhoneInternational'?: string;
    /**
     * The extension of the phone number.  The extension is the \"123\" section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers
     * @type {string}
     * @memberof PhoneRequest
     */
    'sPhoneExtension'?: string;
}


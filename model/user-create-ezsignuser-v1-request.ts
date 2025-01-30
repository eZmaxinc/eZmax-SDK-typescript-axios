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
 * Request for POST /1/module/user/createEzsignuser
 * @export
 * @interface UserCreateEzsignuserV1Request
 */
export interface UserCreateEzsignuserV1Request {
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof UserCreateEzsignuserV1Request
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The first name of the user
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    /*'sUserFirstname': string;*/
    'sUserFirstname': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    /*'sUserLastname': string;*/
    'sUserLastname': string;
    /**
     * The email address.
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    /*'sEmailAddress': string;*/
    'sEmailAddress': string;
    /**
     * The region of the phone number. (For a North America Number only)  The region is the \"514\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     * @deprecated
     */
    /*'sPhoneRegion': string;*/
    'sPhoneRegion': string;
    /**
     * The exchange of the phone number. (For a North America Number only)  The exchange is the \"990\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     * @deprecated
     */
    /*'sPhoneExchange': string;*/
    'sPhoneExchange': string;
    /**
     * The number of the phone number. (For a North America Number only)  The number is the \"1516\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     * @deprecated
     */
    /*'sPhoneNumber': string;*/
    'sPhoneNumber': string;
    /**
     * The extension of the phone number.  The extension is the \"123\" section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    /*'sPhoneExtension'?: string;*/
    'sPhoneExtension'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserCreateEzsignuserV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserCreateEzsignuserV1Request
 */
export class DataObjectUserCreateEzsignuserV1Request {
   fkiLanguageID:number = 0
   sUserFirstname:string = ''
   sUserLastname:string = ''
   sEmailAddress:string = ''
   sPhoneRegion:string = ''
   sPhoneExchange:string = ''
   sPhoneNumber:string = ''
   sPhoneExtension?:string = undefined
}

/**
 * @export 
 * A UserCreateEzsignuserV1Request Validation Object
 * @class ValidationObjectUserCreateEzsignuserV1Request
 */
export class ValidationObjectUserCreateEzsignuserV1Request {
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sUserFirstname = {
      type: 'string',
      required: true
   }
   sUserLastname = {
      type: 'string',
      required: true
   }
   sEmailAddress = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: true
   }
   sPhoneRegion = {
      type: 'string',
      required: true
   }
   sPhoneExchange = {
      type: 'string',
      required: true
   }
   sPhoneNumber = {
      type: 'string',
      required: true
   }
   sPhoneExtension = {
      type: 'string',
      required: false
   }
} 



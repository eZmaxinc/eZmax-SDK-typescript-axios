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
 * An Email Object
 * @export
 * @interface EmailRequest
 */
export interface EmailRequest {
    /**
     * The unique ID of the Email
     * @type {number}
     * @memberof EmailRequest
     */
    'pkiEmailID'?: number;
    /**
     * The unique ID of the Emailtype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home|
     * @type {number}
     * @memberof EmailRequest
     */
    'fkiEmailtypeID': number;
    /**
     * The email address.
     * @type {string}
     * @memberof EmailRequest
     */
    'sEmailAddress': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EmailRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEmailRequest
 */
export class DataObjectEmailRequest {
   pkiEmailID?:number = undefined
   fkiEmailtypeID:number = 0
   sEmailAddress:string = ''
}

/**
 * @export 
 * A EmailRequest Validation Object
 * @class ValidationObjectEmailRequest
 */
export class ValidationObjectEmailRequest {
   pkiEmailID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: false
   }
   fkiEmailtypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEmailAddress = {
      type: 'string',
      required: true
   }
} 



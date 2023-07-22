/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * An Email Object
 * @export
 * @interface EmailResponse
 */
export interface EmailResponse {
    /**
     * The unique ID of the Email
     * @type {number}
     * @memberof EmailResponse
     */
    'pkiEmailID': number;
    /**
     * The unique ID of the Emailtype.  Valid values:  |Value|Description| |-|-| |1|Office| |2|Home|
     * @type {number}
     * @memberof EmailResponse
     */
    'fkiEmailtypeID': number;
    /**
     * The email address.
     * @type {string}
     * @memberof EmailResponse
     */
    'sEmailAddress': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EmailResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEmailResponse
 */
export class DataObjectEmailResponse {
   pkiEmailID:number = 0
   fkiEmailtypeID:number = 0
   sEmailAddress:string = ''
}

/**
 * @export 
 * A EmailResponse Validation Object
 * @class ValidationObjectEmailResponse
 */
export class ValidationObjectEmailResponse {
   pkiEmailID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: true
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



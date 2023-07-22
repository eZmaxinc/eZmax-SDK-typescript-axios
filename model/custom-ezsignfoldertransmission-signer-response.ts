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
 * A form Signer Object in the context of an Ezsignfoldertransmissions
 * @export
 * @interface CustomEzsignfoldertransmissionSignerResponse
 */
export interface CustomEzsignfoldertransmissionSignerResponse {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomEzsignfoldertransmissionSignerResponse
     */
    'fkiUserID'?: number;
    /**
     * The First name of the contact
     * @type {string}
     * @memberof CustomEzsignfoldertransmissionSignerResponse
     */
    'sContactFirstname': string;
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof CustomEzsignfoldertransmissionSignerResponse
     */
    'sContactLastname': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignfoldertransmissionSignerResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignfoldertransmissionSignerResponse
 */
export class DataObjectCustomEzsignfoldertransmissionSignerResponse {
   fkiUserID?:number = undefined
   sContactFirstname:string = ''
   sContactLastname:string = ''
}

/**
 * @export 
 * A CustomEzsignfoldertransmissionSignerResponse Validation Object
 * @class ValidationObjectCustomEzsignfoldertransmissionSignerResponse
 */
export class ValidationObjectCustomEzsignfoldertransmissionSignerResponse {
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sContactFirstname = {
      type: 'string',
      required: true
   }
   sContactLastname = {
      type: 'string',
      required: true
   }
} 



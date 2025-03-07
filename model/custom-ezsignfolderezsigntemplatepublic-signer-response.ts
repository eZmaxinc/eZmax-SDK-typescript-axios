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
 * A form Signer Object in the context of an Ezsignfoldertransmissions
 * @export
 * @interface CustomEzsignfolderezsigntemplatepublicSignerResponse
 */
export interface CustomEzsignfolderezsigntemplatepublicSignerResponse {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomEzsignfolderezsigntemplatepublicSignerResponse
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Ezsignsignergroup
     * @type {number}
     * @memberof CustomEzsignfolderezsigntemplatepublicSignerResponse
     */
    /*'fkiEzsignsignergroupID'?: number;*/
    'fkiEzsignsignergroupID'?: number;
    /**
     * The First name of the contact
     * @type {string}
     * @memberof CustomEzsignfolderezsigntemplatepublicSignerResponse
     */
    /*'sContactFirstname'?: string;*/
    'sContactFirstname'?: string;
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof CustomEzsignfolderezsigntemplatepublicSignerResponse
     */
    /*'sContactLastname'?: string;*/
    'sContactLastname'?: string;
    /**
     * The Description of the Ezsignsignergroup in the language of the requester
     * @type {string}
     * @memberof CustomEzsignfolderezsigntemplatepublicSignerResponse
     */
    /*'sEzsignsignergroupDescriptionX'?: string;*/
    'sEzsignsignergroupDescriptionX'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignfolderezsigntemplatepublicSignerResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignfolderezsigntemplatepublicSignerResponse
 */
export class DataObjectCustomEzsignfolderezsigntemplatepublicSignerResponse {
   fkiUserID?:number = undefined
   fkiEzsignsignergroupID?:number = undefined
   sContactFirstname?:string = undefined
   sContactLastname?:string = undefined
   sEzsignsignergroupDescriptionX?:string = undefined
}

/**
 * @export 
 * A CustomEzsignfolderezsigntemplatepublicSignerResponse Validation Object
 * @class ValidationObjectCustomEzsignfolderezsigntemplatepublicSignerResponse
 */
export class ValidationObjectCustomEzsignfolderezsigntemplatepublicSignerResponse {
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignsignergroupID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   sContactFirstname = {
      type: 'string',
      pattern: /^.{1,20}$/,
      required: false
   }
   sContactLastname = {
      type: 'string',
      pattern: /^.{1,25}$/,
      required: false
   }
   sEzsignsignergroupDescriptionX = {
      type: 'string',
      required: false
   }
} 



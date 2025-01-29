/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Payload for POST /1/object/ezsigntemplatepublic/createEzsignfolder
 * @export
 * @interface EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload
 */
export interface EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload {
    /**
     * The url to sign the Ezsignfolder created by the Ezsigntemplatepublic. Only used when fkiUserLogintypeID is **No validation** or **Sms only**
     * @type {string}
     * @memberof EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload
     */
    /*'sEzsigntemplatepublicSigningurl'?: string;*/
    'sEzsigntemplatepublicSigningurl'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload
 */
export class DataObjectEzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload {
   sEzsigntemplatepublicSigningurl?:string = undefined
}

/**
 * @export 
 * A EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload {
   sEzsigntemplatepublicSigningurl = {
      type: 'string',
      pattern: /^(https|http):\/\/[^\s\/$.?#].[^\s]*$/,
      required: false
   }
} 



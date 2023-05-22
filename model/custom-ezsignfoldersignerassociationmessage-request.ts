/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A custom message Object in the context of an Ezsignfolder\'s send function
 * @export
 * @interface CustomEzsignfoldersignerassociationmessageRequest
 */
export interface CustomEzsignfoldersignerassociationmessageRequest {
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof CustomEzsignfoldersignerassociationmessageRequest
     */
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof CustomEzsignfoldersignerassociationmessageRequest
     */
    'tEzsignfoldersignerassociationMessage'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomEzsignfoldersignerassociationmessageRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomEzsignfoldersignerassociationmessageRequest
 */
export class DataObjectCustomEzsignfoldersignerassociationmessageRequest {
   fkiEzsignfoldersignerassociationID:number = 0
   tEzsignfoldersignerassociationMessage?:string = undefined
}

/**
 * @export 
 * A CustomEzsignfoldersignerassociationmessageRequest Validation Object
 * @class ValidationObjectCustomEzsignfoldersignerassociationmessageRequest
 */
export class ValidationObjectCustomEzsignfoldersignerassociationmessageRequest {
   fkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   tEzsignfoldersignerassociationMessage = {
      type: 'string',
      required: false
   }
} 



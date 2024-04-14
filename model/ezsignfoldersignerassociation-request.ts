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
 * An Ezsignfoldersignerassociation Object
 * @export
 * @interface EzsignfoldersignerassociationRequest
 */
export interface EzsignfoldersignerassociationRequest {
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignfoldersignerassociationRequest
     */
    /*'pkiEzsignfoldersignerassociationID'?: number;*/
    'pkiEzsignfoldersignerassociationID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignfoldersignerassociationRequest
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The unique ID of the Ezsignsignergroup
     * @type {number}
     * @memberof EzsignfoldersignerassociationRequest
     */
    /*'fkiEzsignsignergroupID'?: number;*/
    'fkiEzsignsignergroupID'?: number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldersignerassociationRequest
     */
    /*'fkiEzsignfolderID': number;*/
    'fkiEzsignfolderID': number;
    /**
     * If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\'t required to sign the document.
     * @type {boolean}
     * @memberof EzsignfoldersignerassociationRequest
     */
    /*'bEzsignfoldersignerassociationReceivecopy'?: boolean;*/
    'bEzsignfoldersignerassociationReceivecopy'?: boolean;
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfoldersignerassociationRequest
     */
    /*'tEzsignfoldersignerassociationMessage'?: string;*/
    'tEzsignfoldersignerassociationMessage'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldersignerassociationRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldersignerassociationRequest
 */
export class DataObjectEzsignfoldersignerassociationRequest {
   pkiEzsignfoldersignerassociationID?:number = undefined
   fkiUserID?:number = undefined
   fkiEzsignsignergroupID?:number = undefined
   fkiEzsignfolderID:number = 0
   bEzsignfoldersignerassociationReceivecopy?:boolean = undefined
   tEzsignfoldersignerassociationMessage?:string = undefined
}

/**
 * @export 
 * A EzsignfoldersignerassociationRequest Validation Object
 * @class ValidationObjectEzsignfoldersignerassociationRequest
 */
export class ValidationObjectEzsignfoldersignerassociationRequest {
   pkiEzsignfoldersignerassociationID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
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
   fkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsignfoldersignerassociationReceivecopy = {
      type: 'boolean',
      required: false
   }
   tEzsignfoldersignerassociationMessage = {
      type: 'string',
      required: false
   }
} 



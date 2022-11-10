/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
    'pkiEzsignfoldersignerassociationID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignfoldersignerassociationRequest
     */
    'fkiUserID'?: number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldersignerassociationRequest
     */
    'fkiEzsignfolderID': number;
    /**
     * If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\'t required to sign the document.
     * @type {boolean}
     * @memberof EzsignfoldersignerassociationRequest
     */
    'bEzsignfoldersignerassociationReceivecopy'?: boolean;
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfoldersignerassociationRequest
     */
    'tEzsignfoldersignerassociationMessage'?: string;
}
/**
 * A EzsignfoldersignerassociationRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldersignerassociationRequest
 */
export class DefaultObjectEzsignfoldersignerassociationRequest extends DefaultObject {
   pkiEzsignfoldersignerassociationID?:number = undefined
   fkiUserID?:number = undefined
   fkiEzsignfolderID:number = 0
   bEzsignfoldersignerassociationReceivecopy?:boolean = undefined
   tEzsignfoldersignerassociationMessage?:string = undefined
}



/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
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
 * @interface EzsignfoldersignerassociationResponse
 */
export interface EzsignfoldersignerassociationResponse {
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof EzsignfoldersignerassociationResponse
     */
    'pkiEzsignfoldersignerassociationID': number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof EzsignfoldersignerassociationResponse
     */
    'fkiEzsignfolderID': number;
    /**
     * If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\'t required to sign the document.
     * @type {boolean}
     * @memberof EzsignfoldersignerassociationResponse
     */
    'bEzsignfoldersignerassociationReceivecopy': boolean;
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfoldersignerassociationResponse
     */
    'tEzsignfoldersignerassociationMessage': string;
}
/**
 * A EzsignfoldersignerassociationResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldersignerassociationResponse
 */
export class DefaultObjectEzsignfoldersignerassociationResponse extends DefaultObject {
   pkiEzsignfoldersignerassociationID:number = 0
   fkiEzsignfolderID:number = 0
   bEzsignfoldersignerassociationReceivecopy:boolean = false
   tEzsignfoldersignerassociationMessage:string = ''
}



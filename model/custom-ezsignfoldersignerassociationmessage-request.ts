/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

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
 * A CustomEzsignfoldersignerassociationmessageRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomEzsignfoldersignerassociationmessageRequest
 */
export class DefaultObjectCustomEzsignfoldersignerassociationmessageRequest extends DefaultObject {
   fkiEzsignfoldersignerassociationID:number = 0
   tEzsignfoldersignerassociationMessage?:string = undefined
}



/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomFormDataSignerResponse } from './custom-form-data-signer-response';

import { DefaultObject } from '../base'

/**
 * A form Data Document Object 
 * @export
 * @interface CustomFormDataDocumentResponse
 */
export interface CustomFormDataDocumentResponse {
    /**
     * The unique ID of the Ezsigndocument
     * @type {number}
     * @memberof CustomFormDataDocumentResponse
     */
    'pkiEzsigndocumentID': number;
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomFormDataDocumentResponse
     */
    'fkiEzsignfolderID': number;
    /**
     * The name of the document that will be presented to Ezsignfoldersignerassociations
     * @type {string}
     * @memberof CustomFormDataDocumentResponse
     */
    'sEzsigndocumentName': string;
    /**
     * The date and time at which the object was last modified
     * @type {string}
     * @memberof CustomFormDataDocumentResponse
     */
    'dtModifiedDate': string;
    /**
     * 
     * @type {Array<CustomFormDataSignerResponse>}
     * @memberof CustomFormDataDocumentResponse
     */
    'a_objFormDataSigner': Array<CustomFormDataSignerResponse>;
}
/**
 * A CustomFormDataDocumentResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectCustomFormDataDocumentResponse
 */
export class DefaultObjectCustomFormDataDocumentResponse extends DefaultObject {
   pkiEzsigndocumentID:number = 0
   fkiEzsignfolderID:number = 0
   sEzsigndocumentName:string = ''
   dtModifiedDate:string = ''
   a_objFormDataSigner:Array<CustomFormDataSignerResponse> = []
}



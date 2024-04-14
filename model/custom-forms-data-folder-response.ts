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


// May contain unused imports in some cases
// @ts-ignore
import { CustomFormDataDocumentResponse } from './custom-form-data-document-response';

/**
 * A forms Data Folder Object
 * @export
 * @interface CustomFormsDataFolderResponse
 */
export interface CustomFormsDataFolderResponse {
    /**
     * The unique ID of the Ezsignfolder
     * @type {number}
     * @memberof CustomFormsDataFolderResponse
     */
    /*'pkiEzsignfolderID': number;*/
    'pkiEzsignfolderID': number;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof CustomFormsDataFolderResponse
     */
    /*'sEzsignfolderDescription': string;*/
    'sEzsignfolderDescription': string;
    /**
     * 
     * @type {Array<CustomFormDataDocumentResponse>}
     * @memberof CustomFormsDataFolderResponse
     */
    /*'a_objFormDataDocument': Array<CustomFormDataDocumentResponse>;*/
    'a_objFormDataDocument': Array<CustomFormDataDocumentResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomFormsDataFolderResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomFormsDataFolderResponse
 */
export class DataObjectCustomFormsDataFolderResponse {
   pkiEzsignfolderID:number = 0
   sEzsignfolderDescription:string = ''
   a_objFormDataDocument:Array<CustomFormDataDocumentResponse> = []
}

/**
 * @export 
 * A CustomFormsDataFolderResponse Validation Object
 * @class ValidationObjectCustomFormsDataFolderResponse
 */
export class ValidationObjectCustomFormsDataFolderResponse {
   pkiEzsignfolderID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsignfolderDescription = {
      type: 'string',
      required: true
   }
   a_objFormDataDocument = {
      type: 'array',
      required: true
   }
} 



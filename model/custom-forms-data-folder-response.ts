/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


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
    'pkiEzsignfolderID': number;
    /**
     * The description of the Ezsignfolder
     * @type {string}
     * @memberof CustomFormsDataFolderResponse
     */
    'sEzsignfolderDescription': string;
    /**
     * 
     * @type {Array<CustomFormDataDocumentResponse>}
     * @memberof CustomFormsDataFolderResponse
     */
    'a_objFormDataDocument': Array<CustomFormDataDocumentResponse>;
}


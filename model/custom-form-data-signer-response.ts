/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { CustomFormDataEzsignformfieldgroupResponse } from './custom-form-data-ezsignformfieldgroup-response';

/**
 * A form Data Signer Object
 * @export
 * @interface CustomFormDataSignerResponse
 */
export interface CustomFormDataSignerResponse {
    /**
     * The unique ID of the Ezsignfoldersignerassociation
     * @type {number}
     * @memberof CustomFormDataSignerResponse
     */
    'fkiEzsignfoldersignerassociationID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof CustomFormDataSignerResponse
     */
    'fkiUserID'?: number;
    /**
     * The First name of the contact
     * @type {string}
     * @memberof CustomFormDataSignerResponse
     */
    'sContactFirstname': string;
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof CustomFormDataSignerResponse
     */
    'sContactLastname': string;
    /**
     * 
     * @type {Array<CustomFormDataEzsignformfieldgroupResponse>}
     * @memberof CustomFormDataSignerResponse
     */
    'a_objEzsignformfieldgroup': Array<CustomFormDataEzsignformfieldgroupResponse>;
}


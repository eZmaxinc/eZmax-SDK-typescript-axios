/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * A Department AutocompleteElement Response
 * @export
 * @interface DepartmentAutocompleteElementResponse
 */
export interface DepartmentAutocompleteElementResponse {
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof DepartmentAutocompleteElementResponse
     */
    'sCompanyNameX': string;
    /**
     * The Name of the Department in the language of the requester
     * @type {string}
     * @memberof DepartmentAutocompleteElementResponse
     */
    'sDepartmentNameX': string;
    /**
     * The unique ID of the Department
     * @type {number}
     * @memberof DepartmentAutocompleteElementResponse
     */
    'pkiDepartmentID': number;
    /**
     * Whether the Department is active or not
     * @type {boolean}
     * @memberof DepartmentAutocompleteElementResponse
     */
    'bDepartmentIsactive': boolean;
}
/**
 * A DepartmentAutocompleteElementResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectDepartmentAutocompleteElementResponse
 */
export class DefaultObjectDepartmentAutocompleteElementResponse extends DefaultObject {
   sCompanyNameX:string = ''
   sDepartmentNameX:string = ''
   pkiDepartmentID:number = 0
   bDepartmentIsactive:boolean = false
}



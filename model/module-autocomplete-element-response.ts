/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Module AutocompleteElement Response
 * @export
 * @interface ModuleAutocompleteElementResponse
 */
export interface ModuleAutocompleteElementResponse {
    /**
     * The unique ID of the Module
     * @type {number}
     * @memberof ModuleAutocompleteElementResponse
     */
    /*'pkiModuleID': number;*/
    'pkiModuleID': number;
    /**
     * The Name of the Module in the language of the requester
     * @type {string}
     * @memberof ModuleAutocompleteElementResponse
     */
    /*'sModuleNameX': string;*/
    'sModuleNameX': string;
    /**
     * Whether the Module is active or not
     * @type {boolean}
     * @memberof ModuleAutocompleteElementResponse
     */
    /*'bModuleIsactive': boolean;*/
    'bModuleIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ModuleAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectModuleAutocompleteElementResponse
 */
export class DataObjectModuleAutocompleteElementResponse {
   pkiModuleID:number = 0
   sModuleNameX:string = ''
   bModuleIsactive:boolean = false
}

/**
 * @export 
 * A ModuleAutocompleteElementResponse Validation Object
 * @class ValidationObjectModuleAutocompleteElementResponse
 */
export class ValidationObjectModuleAutocompleteElementResponse {
   pkiModuleID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sModuleNameX = {
      type: 'string',
      required: true
   }
   bModuleIsactive = {
      type: 'boolean',
      required: true
   }
} 



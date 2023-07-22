/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';

/**
 * A Ezsigntemplatepackage AutocompleteElement Response
 * @export
 * @interface EzsigntemplatepackageAutocompleteElementResponse
 */
export interface EzsigntemplatepackageAutocompleteElementResponse {
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsigntemplatepackageAutocompleteElementResponse
     */
    'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;
    /**
     * The description of the Ezsigntemplatepackage
     * @type {string}
     * @memberof EzsigntemplatepackageAutocompleteElementResponse
     */
    'sEzsigntemplatepackageDescription': string;
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackageAutocompleteElementResponse
     */
    'pkiEzsigntemplatepackageID': number;
    /**
     * Whether the Ezsigntemplatepackage is active or not
     * @type {boolean}
     * @memberof EzsigntemplatepackageAutocompleteElementResponse
     */
    'bEzsigntemplatepackageIsactive': boolean;
    /**
     * Indicates if the element is disabled in the context
     * @type {boolean}
     * @memberof EzsigntemplatepackageAutocompleteElementResponse
     */
    'bDisabled': boolean;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackageAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageAutocompleteElementResponse
 */
export class DataObjectEzsigntemplatepackageAutocompleteElementResponse {
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   sEzsigntemplatepackageDescription:string = ''
   pkiEzsigntemplatepackageID:number = 0
   bEzsigntemplatepackageIsactive:boolean = false
   bDisabled:boolean = false
}

/**
 * @export 
 * A EzsigntemplatepackageAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzsigntemplatepackageAutocompleteElementResponse
 */
export class ValidationObjectEzsigntemplatepackageAutocompleteElementResponse {
   eEzsignfoldertypePrivacylevel = {
      type: 'enum',
      allowableValues: ['User','Usergroup'],
      required: true
   }
   sEzsigntemplatepackageDescription = {
      type: 'string',
      required: true
   }
   pkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsigntemplatepackageIsactive = {
      type: 'boolean',
      required: true
   }
   bDisabled = {
      type: 'boolean',
      required: true
   }
} 



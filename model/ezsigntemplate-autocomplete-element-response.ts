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
import { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';

/**
 * A Ezsigntemplate AutocompleteElement Response
 * @export
 * @interface EzsigntemplateAutocompleteElementResponse
 */
export interface EzsigntemplateAutocompleteElementResponse {
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsigntemplateAutocompleteElementResponse
     */
    'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateAutocompleteElementResponse
     */
    'sEzsigntemplateDescription': string;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateAutocompleteElementResponse
     */
    'pkiEzsigntemplateID': number;
    /**
     * Whether the Ezsigntemplate is active or not
     * @type {boolean}
     * @memberof EzsigntemplateAutocompleteElementResponse
     */
    'bEzsigntemplateIsactive': boolean;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateAutocompleteElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateAutocompleteElementResponse
 */
export class DataObjectEzsigntemplateAutocompleteElementResponse {
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   sEzsigntemplateDescription:string = ''
   pkiEzsigntemplateID:number = 0
   bEzsigntemplateIsactive:boolean = false
}

/**
 * @export 
 * A EzsigntemplateAutocompleteElementResponse Validation Object
 * @class ValidationObjectEzsigntemplateAutocompleteElementResponse
 */
export class ValidationObjectEzsigntemplateAutocompleteElementResponse {
   eEzsignfoldertypePrivacylevel = {
      type: 'enum',
      allowableValues: ['User','Usergroup'],
      required: true
   }
   sEzsigntemplateDescription = {
      type: 'string',
      required: true
   }
   pkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzsigntemplateIsactive = {
      type: 'boolean',
      required: true
   }
} 



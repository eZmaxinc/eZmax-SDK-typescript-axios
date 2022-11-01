/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';

import { DefaultObject } from '../base'

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
 * A EzsigntemplatepackageAutocompleteElementResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageAutocompleteElementResponse
 */
export class DefaultObjectEzsigntemplatepackageAutocompleteElementResponse extends DefaultObject {
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   sEzsigntemplatepackageDescription:string = ''
   pkiEzsigntemplatepackageID:number = 0
   bEzsigntemplatepackageIsactive:boolean = false
   bDisabled:boolean = false
}



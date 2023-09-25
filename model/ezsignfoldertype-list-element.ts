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
 * An Ezsignfoldertype List Element
 * @export
 * @interface EzsignfoldertypeListElement
 */
export interface EzsignfoldertypeListElement {
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignfoldertypeListElement
     */
    'pkiEzsignfoldertypeID': number;
    /**
     * 
     * @type {FieldEEzsignfoldertypePrivacylevel}
     * @memberof EzsignfoldertypeListElement
     */
    'eEzsignfoldertypePrivacylevel': FieldEEzsignfoldertypePrivacylevel;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsignfoldertypeListElement
     */
    'sEzsignfoldertypeNameX': string;
    /**
     * Whether the Ezsignfoldertype is active or not
     * @type {boolean}
     * @memberof EzsignfoldertypeListElement
     */
    'bEzsignfoldertypeIsactive': boolean;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfoldertypeListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeListElement
 */
export class DataObjectEzsignfoldertypeListElement {
   pkiEzsignfoldertypeID:number = 0
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   sEzsignfoldertypeNameX:string = ''
   bEzsignfoldertypeIsactive:boolean = false
}

/**
 * @export 
 * A EzsignfoldertypeListElement Validation Object
 * @class ValidationObjectEzsignfoldertypeListElement
 */
export class ValidationObjectEzsignfoldertypeListElement {
   pkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   eEzsignfoldertypePrivacylevel = {
      type: 'enum',
      allowableValues: ['User','Usergroup'],
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: true
   }
   bEzsignfoldertypeIsactive = {
      type: 'boolean',
      required: true
   }
} 



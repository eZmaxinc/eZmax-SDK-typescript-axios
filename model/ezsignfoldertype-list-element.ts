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
import { FieldEEzsignfoldertypePrivacylevel } from './field-eezsignfoldertype-privacylevel';

import { DefaultObject } from '../base'

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
 * A EzsignfoldertypeListElement Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldertypeListElement
 */
export class DefaultObjectEzsignfoldertypeListElement extends DefaultObject {
   pkiEzsignfoldertypeID:number = 0
   eEzsignfoldertypePrivacylevel:FieldEEzsignfoldertypePrivacylevel = 'User'
   sEzsignfoldertypeNameX:string = ''
   bEzsignfoldertypeIsactive:boolean = false
}



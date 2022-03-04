/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.7
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


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


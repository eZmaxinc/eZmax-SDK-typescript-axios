/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignerResponseCompoundContact } from './ezsignsigner-response-compound-contact';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignsignerResponseCompoundAllOf
 */
export interface EzsignsignerResponseCompoundAllOf {
    /**
     * 
     * @type {EzsignsignerResponseCompoundContact}
     * @memberof EzsignsignerResponseCompoundAllOf
     */
    'objContact': EzsignsignerResponseCompoundContact;
}
/**
 * A EzsignsignerResponseCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignsignerResponseCompoundAllOf
 */
export class DefaultObjectEzsignsignerResponseCompoundAllOf extends DefaultObject {
   objContact:Partial<EzsignsignerResponseCompoundContact> = {}
}



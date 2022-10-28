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
import { EzsignfolderGetObjectV2ResponseMPayload } from './ezsignfolder-get-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignfolderGetObjectV2ResponseAllOf
 */
export interface EzsignfolderGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetObjectV2ResponseMPayload}
     * @memberof EzsignfolderGetObjectV2ResponseAllOf
     */
    'mPayload': EzsignfolderGetObjectV2ResponseMPayload;
}
/**
 * A EzsignfolderGetObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderGetObjectV2ResponseAllOf
 */
export class DefaultObjectEzsignfolderGetObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignfolderGetObjectV2ResponseMPayload> = {}
}



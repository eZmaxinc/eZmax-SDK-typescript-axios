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
import { EzsignfolderGetObjectV1ResponseMPayload } from './ezsignfolder-get-object-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignfolderGetObjectV1ResponseAllOf
 */
export interface EzsignfolderGetObjectV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetObjectV1ResponseMPayload}
     * @memberof EzsignfolderGetObjectV1ResponseAllOf
     */
    'mPayload': EzsignfolderGetObjectV1ResponseMPayload;
}
/**
 * A EzsignfolderGetObjectV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderGetObjectV1ResponseAllOf
 */
export class DefaultObjectEzsignfolderGetObjectV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignfolderGetObjectV1ResponseMPayload> = {}
}



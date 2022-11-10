/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderGetEzsigndocumentsV1ResponseMPayload } from './ezsignfolder-get-ezsigndocuments-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignfolderGetEzsigndocumentsV1ResponseAllOf
 */
export interface EzsignfolderGetEzsigndocumentsV1ResponseAllOf {
    /**
     * 
     * @type {EzsignfolderGetEzsigndocumentsV1ResponseMPayload}
     * @memberof EzsignfolderGetEzsigndocumentsV1ResponseAllOf
     */
    'mPayload': EzsignfolderGetEzsigndocumentsV1ResponseMPayload;
}
/**
 * A EzsignfolderGetEzsigndocumentsV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderGetEzsigndocumentsV1ResponseAllOf
 */
export class DefaultObjectEzsignfolderGetEzsigndocumentsV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsignfolderGetEzsigndocumentsV1ResponseMPayload> = {}
}



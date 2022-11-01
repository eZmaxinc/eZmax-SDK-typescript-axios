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
import { EzsigndocumentGetEzsignsignaturesV1ResponseMPayload } from './ezsigndocument-get-ezsignsignatures-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigndocumentGetEzsignsignaturesV1ResponseAllOf
 */
export interface EzsigndocumentGetEzsignsignaturesV1ResponseAllOf {
    /**
     * 
     * @type {EzsigndocumentGetEzsignsignaturesV1ResponseMPayload}
     * @memberof EzsigndocumentGetEzsignsignaturesV1ResponseAllOf
     */
    'mPayload': EzsigndocumentGetEzsignsignaturesV1ResponseMPayload;
}
/**
 * A EzsigndocumentGetEzsignsignaturesV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentGetEzsignsignaturesV1ResponseAllOf
 */
export class DefaultObjectEzsigndocumentGetEzsignsignaturesV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigndocumentGetEzsignsignaturesV1ResponseMPayload> = {}
}



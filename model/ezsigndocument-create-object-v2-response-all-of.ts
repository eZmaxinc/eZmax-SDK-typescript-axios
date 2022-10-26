/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentCreateObjectV2ResponseMPayload } from './ezsigndocument-create-object-v2-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigndocumentCreateObjectV2ResponseAllOf
 */
export interface EzsigndocumentCreateObjectV2ResponseAllOf {
    /**
     * 
     * @type {EzsigndocumentCreateObjectV2ResponseMPayload}
     * @memberof EzsigndocumentCreateObjectV2ResponseAllOf
     */
    'mPayload': EzsigndocumentCreateObjectV2ResponseMPayload;
}
/**
 * A EzsigndocumentCreateObjectV2ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentCreateObjectV2ResponseAllOf
 */
export class DefaultObjectEzsigndocumentCreateObjectV2ResponseAllOf extends DefaultObject {
   mPayload:Partial<EzsigndocumentCreateObjectV2ResponseMPayload> = {}
}



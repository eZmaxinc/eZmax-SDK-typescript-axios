/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentResponse } from './ezsigndocument-response';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface WebhookEzsignDocumentCompletedAllOf
 */
export interface WebhookEzsignDocumentCompletedAllOf {
    /**
     * 
     * @type {EzsigndocumentResponse}
     * @memberof WebhookEzsignDocumentCompletedAllOf
     */
    'objEzsigndocument': EzsigndocumentResponse;
}
/**
 * A WebhookEzsignDocumentCompletedAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookEzsignDocumentCompletedAllOf
 */
export class DefaultObjectWebhookEzsignDocumentCompletedAllOf extends DefaultObject {
   objEzsigndocument:Partial<EzsigndocumentResponse> = {}
}



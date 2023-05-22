/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetActionableElementsV1ResponseMPayload } from './ezsigndocument-get-actionable-elements-v1-response-mpayload';

/**
 * 
 * @export
 * @interface EzsigndocumentGetActionableElementsV1ResponseAllOf
 */
export interface EzsigndocumentGetActionableElementsV1ResponseAllOf {
    /**
     * 
     * @type {EzsigndocumentGetActionableElementsV1ResponseMPayload}
     * @memberof EzsigndocumentGetActionableElementsV1ResponseAllOf
     */
    'mPayload': EzsigndocumentGetActionableElementsV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetActionableElementsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetActionableElementsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentGetActionableElementsV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetActionableElementsV1ResponseAllOf
 */
export class DataObjectEzsigndocumentGetActionableElementsV1ResponseAllOf {
   mPayload:EzsigndocumentGetActionableElementsV1ResponseMPayload = new DataObjectEzsigndocumentGetActionableElementsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentGetActionableElementsV1ResponseAllOf Validation Object
 * @class ValidationObjectEzsigndocumentGetActionableElementsV1ResponseAllOf
 */
export class ValidationObjectEzsigndocumentGetActionableElementsV1ResponseAllOf {
   mPayload = new ValidationObjectEzsigndocumentGetActionableElementsV1ResponseMPayload()
} 


